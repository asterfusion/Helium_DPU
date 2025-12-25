/*
 * et3600.c - ET3600 port control plugin
 *
 * Controls SFP/QSFP power/reset via sysfs when interfaces are admin up/down.
 */

#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vlib/log.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <et3600/et3600.h>

typedef enum
{
  ET3600_PORT_TYPE_SFP,
  ET3600_PORT_TYPE_QSFP,
} et3600_port_type_t;

typedef struct
{
  et3600_port_type_t type;
  u8 port_id; /* 1-based */
  const char *names[3]; /* aliases terminated by NULL */
} et3600_port_map_t;

/* interface name -> physical port mapping */
static const et3600_port_map_t et3600_port_map[] = {
  /* QSFP */
  { ET3600_PORT_TYPE_QSFP, 1, { "C1", "bobm2", 0 } },
  { ET3600_PORT_TYPE_QSFP, 2, { "C2", "bobm3", 0 } },

  /* SFP */
  { ET3600_PORT_TYPE_SFP, 1, { "X1", "bobm1", 0 } },
  { ET3600_PORT_TYPE_SFP, 2, { "X2", "bobm0", 0 } },
};

static i8 et3600_last_state[ARRAY_LEN (et3600_port_map)];

VLIB_REGISTER_LOG_CLASS (et3600_log) = {
  .class_name = "et3600",
  .subclass_name = "port-control",
};

/* Default sysfs base for ET3600 */
#define ET3600_SYSFS_BASE "/sys/bus/i2c/devices/4-0040/"
#define ET3600_SYSFS_PATH_MAX 256

static int
et3600_write_sysfs (const char *path, const char *value)
{
  int fd = open (path, O_WRONLY);
  if (fd < 0)
    return -errno;

  ssize_t rv = write (fd, value, strlen (value));
  if (rv < 0)
    {
      int err = -errno;
      close (fd);
      return err;
    }

  close (fd);
  return 0;
}

static int
et3600_set_port_state (const et3600_port_map_t *map, int is_up)
{
  char path[ET3600_SYSFS_PATH_MAX];
  const char *value = 0;
  int n;

  if (map->type == ET3600_PORT_TYPE_SFP)
    {
      n = snprintf (path, sizeof (path), "%sET3600_SFP/sfp%u_tx_disable",
		    ET3600_SYSFS_BASE, map->port_id);
      value = is_up ? "0" : "1";
    }
  else
    {
      n = snprintf (path, sizeof (path), "%sET3600_QSFP/qsfp%u_reset",
		    ET3600_SYSFS_BASE, map->port_id);
      value = is_up ? "1" : "0";
    }

  if (n < 0 || n >= (int) sizeof (path))
    return -ENAMETOOLONG;

  return et3600_write_sysfs (path, value);
}

static const et3600_port_map_t *
et3600_lookup_by_if_name (const char *if_name)
{
  if (!if_name)
    return 0;

  for (u32 i = 0; i < ARRAY_LEN (et3600_port_map); i++)
    {
      const et3600_port_map_t *m = &et3600_port_map[i];
      for (u32 j = 0; j < ARRAY_LEN (m->names) && m->names[j]; j++)
	{
	  const char *n = m->names[j];
	  size_t len = strlen (n);

	  if (strncasecmp (if_name, n, len) == 0 &&
	      (if_name[len] == 0 || if_name[len] == '.' ||
	       if_name[len] == '/' || if_name[len] == '-'))
	    return m;
	}
    }

  return 0;
}

static clib_error_t *
et3600_sw_interface_admin_up_down (vnet_main_t *vnm, u32 sw_if_index,
				   u32 flags)
{
  const et3600_port_map_t *map;
  vnet_hw_interface_t *hw;
  int is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  int rv;
  u32 map_index;

  if (!vnet_get_sup_hw_interface (vnm, sw_if_index))
    return 0;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw || !hw->name)
    return 0;

  map = et3600_lookup_by_if_name ((char *) hw->name);
  if (!map)
    {
      et3600_log_warn ("interface %s not mapped, ignore",
		     (char *) hw->name);
      return 0;
    }

  map_index = map - et3600_port_map;
  if (et3600_last_state[map_index] == is_up)
    return 0;

  rv = et3600_set_port_state (map, is_up);
  if (rv)
    {
      et3600_log_warn ("set %s%u %s failed: %s",
		     map->type == ET3600_PORT_TYPE_SFP ? "sfp" : "qsfp",
		     map->port_id, is_up ? "up" : "down", strerror (-rv));
      return 0;
    }

  et3600_last_state[map_index] = is_up;
  et3600_log_notice ("%s%u set %s",
		   map->type == ET3600_PORT_TYPE_SFP ? "sfp" : "qsfp",
		   map->port_id, is_up ? "up" : "down");
  return 0;
}


static clib_error_t *
et3600_hw_interface_add_del (vnet_main_t *vnm, u32 hw_if_index, u32 is_create)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  const et3600_port_map_t *map = et3600_lookup_by_if_name ((char *) hw->name);
  if (!map)
    return 0;

  et3600_last_state[map - et3600_port_map] = -1;
  et3600_set_port_state (map, 0 /* down */);
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (et3600_sw_interface_admin_up_down);
VNET_HW_INTERFACE_ADD_DEL_FUNCTION (et3600_hw_interface_add_del);

static clib_error_t *
et3600_init (vlib_main_t *vm)
{
  for (u32 i = 0; i < ARRAY_LEN (et3600_last_state); i++)
    et3600_last_state[i] = -1;
  return 0;
}

VLIB_INIT_FUNCTION (et3600_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "ET3600 port control plugin",
};
/* *INDENT-ON* */
