#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/interface_funcs.h>
#include <vnet/plugin/plugin.h>
#include <softforward/asic_priv.h>
#include <vpp/app/version.h>

asic_private_main_t ap_main;

/* *INDENT-OFF* */
/* Hook up output features */
VNET_FEATURE_INIT (post_asic_private_node, static) = {
  .arc_name = "interface-output",
  .node_name = "post-asic-private",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

int asic_priv_proc_enable(u32 sw_if_index)
{
    int ret = 0;
    asic_priv_interface_t *i;
    asic_private_main_t *apm = &ap_main;
    vnet_sw_interface_t *sw;

    pool_foreach (i, apm->interfaces,
    ({
     if (i->sw_if_index == sw_if_index)
        return VNET_API_ERROR_VALUE_EXIST;
    }));

    sw = vnet_get_sw_interface(apm->vnet_main, sw_if_index);

    pool_get (apm->interfaces, i);
    i->sw_if_index = sw_if_index;
    i->hw_if_index = sw->hw_if_index;
    i->flag = 0;

    ret = vnet_hw_interface_rx_redirect_to_node(apm->vnet_main, sw->hw_if_index, apm->pre_asic_private_node);
    if (ret != 0 )
        return ret;
    ret = vnet_feature_enable_disable("interface-output", "post-asic-private", sw_if_index, 1, 0 ,0);
    if (ret != 0 )
        return ret;

    return 0;
}

int asic_priv_proc_disable(u32 sw_if_index)
{
    int ret;
    asic_priv_interface_t *check = NULL;
    asic_priv_interface_t *i = NULL;
    asic_private_main_t *apm = &ap_main;

    pool_foreach (check, apm->interfaces,
    ({
        if (check->sw_if_index == sw_if_index)
        {
           i = check;
           break;
        }
    }));
    if (i)
    {
        ret = vnet_hw_interface_rx_redirect_to_node(apm->vnet_main, i->hw_if_index, ~0);
        if (ret != 0 )
            return ret;
        ret = vnet_feature_enable_disable("interface-output", "post-asic-private", sw_if_index, 0, 0 ,0);
        if (ret != 0 )
            return ret;
    }
    else
        return VNET_API_ERROR_NO_SUCH_ENTRY;

    pool_put(apm->interfaces, i);
    return 0;
}

static clib_error_t *
asic_priv_init (vlib_main_t * vm)
{
    asic_private_main_t *apm = &ap_main;
    vlib_node_t *node;

    apm->vlib_main = vm;
    apm->vnet_main = vnet_get_main ();

    node = vlib_get_node_by_name (vm, (u8 *) "pre-asic-private");
    apm->pre_asic_private_node = node->index;

    node = vlib_get_node_by_name (vm, (u8 *) "post-asic-private");
    apm->post_asic_private_node = node->index;

    return 0;
}

VLIB_INIT_FUNCTION (asic_priv_init);
