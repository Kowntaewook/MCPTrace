/* Opt-in in-process Mach VM capture for an isolated macOS MCP host.
 * Compile as a Node N-API addon. Captures private writable pages only.
 * The binary output is sensitive and must remain outside the repository.
 */
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <node_api.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int write_all(int fd, const void *data, size_t size) {
  const uint8_t *p = data;
  while (size) {
    ssize_t n = write(fd, p, size);
    if (n <= 0) return -1;
    p += n;
    size -= (size_t)n;
  }
  return 0;
}

static napi_value snapshot(napi_env env, napi_callback_info info) {
  napi_value argv[1], result;
  size_t argc = 1, length = 0;
  char path[4096];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
      napi_get_value_string_utf8(env, argv[0], path, sizeof(path), &length) != napi_ok ||
      length == 0 || length >= sizeof(path) - 1) {
    napi_throw_type_error(env, NULL, "snapshot(path) requires a short path");
    return NULL;
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    napi_throw_error(env, NULL, "cannot create snapshot file");
    return NULL;
  }
  const uint64_t limit = 256ULL * 1024 * 1024;
  uint64_t bytes = 0, regions = 0, errors = 0;
  mach_vm_address_t cursor = 0;
  uint8_t buffer[65536];
  const size_t page_size = (size_t)getpagesize();
  while (bytes < limit) {
    mach_vm_address_t address = cursor;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t region;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t status = mach_vm_region(mach_task_self(), &address, &size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (status != KERN_SUCCESS || size == 0 || address + size <= address) break;
    cursor = address + size;
    if (region.shared || (region.protection & (VM_PROT_READ | VM_PROT_WRITE)) !=
                         (VM_PROT_READ | VM_PROT_WRITE)) continue;
    regions++;
    size_t pages = (size_t)((size + page_size - 1) / page_size);
    unsigned char *residency = calloc(pages, 1);
    if (!residency || mincore((void *)address, (size_t)size, (char *)residency) != 0) {
      free(residency);
      errors++;
      continue;
    }
    for (size_t page = 0; page < pages && bytes < limit;) {
      if (!(residency[page] & MINCORE_INCORE)) {
        page++;
        continue;
      }
      mach_vm_address_t offset = address + page * page_size;
      mach_vm_size_t requested = 0;
      while (page < pages && (residency[page] & MINCORE_INCORE) &&
             requested + page_size <= sizeof(buffer) &&
             requested + page_size <= limit - bytes) {
        requested += page_size;
        page++;
      }
      if (!requested) break;
      mach_vm_size_t received = 0;
      status = mach_vm_read_overwrite(mach_task_self(), offset, requested,
          (mach_vm_address_t)buffer, &received);
      if (status == KERN_SUCCESS && received > 0) {
        uint64_t where = offset;
        uint32_t length32 = (uint32_t)received;
        if (write_all(fd, &where, sizeof(where)) ||
            write_all(fd, &length32, sizeof(length32)) ||
            write_all(fd, buffer, (size_t)received)) {
          close(fd);
          napi_throw_error(env, NULL, "snapshot write failed");
          return NULL;
        }
        bytes += received;
      } else {
        errors++;
      }
    }
    free(residency);
  }
  close(fd);
  char summary[256];
  snprintf(summary, sizeof(summary),
      "{\"scanned_bytes\":%llu,\"private_writable_regions\":%llu,\"read_errors\":%llu,\"truncated_at_256_mib\":%s}",
      (unsigned long long)bytes, (unsigned long long)regions,
      (unsigned long long)errors, bytes >= limit ? "true" : "false");
  napi_create_string_utf8(env, summary, NAPI_AUTO_LENGTH, &result);
  return result;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value function;
  napi_create_function(env, "snapshot", NAPI_AUTO_LENGTH, snapshot, NULL, &function);
  napi_set_named_property(env, exports, "snapshot", function);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
