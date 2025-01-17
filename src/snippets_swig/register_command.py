def register_group(self, cmd, summary):
    help_desc = RzCmdDescHelp()
    help_desc.thisown = False
    help_desc.summary = summary
    self.rcmd.register_swig_command(cmd, None, None, help_desc)


import inspect


def register_command(self, cmd, fn):
    params = list(inspect.signature(fn).parameters.values())

    core_arg = None
    if len(params) > 0 and params[0].annotation == RzCore:
        core_arg = params[0].name
        params = params[1:]

    desc_args = Array_RzCmdDescArg(len(params) + 1)
    desc_args.thisown = False
    for i, param in enumerate(params):
        if not param.annotation:
            raise Exception(f"Parameter {param.name} has no annotation")

        desc_arg = RzCmdDescArg()
        desc_arg.name = param.name

        if param.annotation == str:
            desc_arg.type = RZ_CMD_ARG_TYPE_STRING
        elif param.annotation == RzNumArg:
            desc_arg.type = RZ_CMD_ARG_TYPE_RZNUM
        elif param.annotation == int:
            desc_arg.type = RZ_CMD_ARG_TYPE_NUM
        elif param.annotation == RzFilenameArg:
            desc_arg.type = RZ_CMD_ARG_TYPE_FILE
        elif param.annotation == RzFlagItem:
            desc_arg.type = RZ_CMD_ARG_TYPE_FLAG
        elif param.annotation == RzAnalysisFunction:
            desc_arg.type = RZ_CMD_ARG_TYPE_FCN
        else:
            raise Exception(
                f"Parameter {param.name} has unknown type {param.annotation}"
            )

        desc_arg.thisown = False
        desc_args[i] = desc_arg

    null_arg = RzCmdDescArg()
    null_arg.thisown = False
    desc_args[len(params)] = null_arg

    help_desc = RzCmdDescHelp()
    help_desc.thisown = False
    help_desc.args = desc_args.cast()

    class wrapper(CmdDirector):
        def run(self, core, argc, argv):
            try:
                args = {}
                args_array = Array_String.frompointer(argv)
                if core_arg:
                    args[core_arg] = core
                for i, param in enumerate(params):
                    arg = args_array[i + 1]
                    if param.annotation == RzNumArg:
                        arg = core.num.math(arg)
                    elif param.annotation == int:
                        arg = int(arg)
                    elif param.annotation == RzFlagItem:
                        arg = core.flags.get(arg)
                    elif param.annotation == RzAnalysisFunction:
                        arg = core.analysis.get_function_byname(arg)
                    args[param.name] = arg
                return fn(**args)
            except Exception as e:
                print(e)

    director = wrapper()
    director.__disown__()
    self.rcmd.register_swig_command(cmd, director, help_desc)
