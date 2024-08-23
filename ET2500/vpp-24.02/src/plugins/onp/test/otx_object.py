# Test case objects can make use of local registers to store their objects.
# Control of objects are with user. Cleanup has to be called explicitely.

# Test case object should contain 'update_register' variable defined, to update
# in local register. And 'update_ipsec_register', to update in
# local_register_ipsec_obj.
# Two registers are created, so test cases can opt for clearing
# only ipsec objects instead of winding up all vpp objects of the test case.


def otx_update_ipsec_into_local_register(tc_obj, vpp_obj):
    if (
        hasattr(tc_obj, "update_ipsec_register")
        and tc_obj.update_ipsec_register is True
    ):
        tc_obj.local_register_ipsec_objs.append(vpp_obj)


def otx_update_local_register(tc_obj, vpp_obj):
    if hasattr(tc_obj, "update_register") and tc_obj.update_register is True:
        tc_obj.local_register.append(vpp_obj)
