#kw_override PLT_ASSERT(cond) do { if (!(cond)) abort(); } while (0)
#kw_override PLT_ASSERT_FP(cond) do { if (!(cond)) abort(); } while (0)
#kw_override plt_panic(cond) do { abort(); } while (0)
