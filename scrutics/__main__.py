"""
Scrutics entry point.
No args + interactive terminal -> TUI
--headless or piped stdout     -> headless CLI
doctor subcommand              -> diagnostics report
--live/--file without headless -> TUI with mode pre-loaded
"""
import sys
from scrutics.diagnostics import check_dependencies


def main():
    import scrutics.signals as signals
    signals.setup()

    from scrutics.cli import build_parser, run_headless, run_doctor, run_ai, run_ask, run_oui, should_use_tui

    # No arguments and interactive terminal → TUI
    if len(sys.argv) == 1:
        deps = check_dependencies(headless=False)
        missing = [d for d in deps if not d["ok"]]
        if missing:
            print("\n[!] Missing dependencies:\n")
            for d in missing:
                print(f"  {d['name']:<12}  install: {d['install_cmd']}")
            print()
            sys.exit(1)
        from scrutics.ui.tui import run
        run()
        return

    args = build_parser().parse_args()

    # doctor subcommand
    if getattr(args, "command", None) == "doctor":
        sys.exit(run_doctor(output_dir=getattr(args, "output", "output")))

    # oui subcommand
    if getattr(args, "command", None) == "oui":
        sys.exit(run_oui(args))

    # ai subcommand (and its backward-compat alias 'ask')
    if getattr(args, "command", None) in ("ai", "ask"):
        sys.exit(run_ai(args))
    
    # list-models subcommand
    if getattr(args, "command", None) == "list-models":
        from scrutics.cli import run_list_models
        sys.exit(run_list_models(args))

    headless = not should_use_tui(args)
    deps = check_dependencies(headless=headless)
    missing = [d for d in deps if not d["ok"]]
    if missing:
        print("\n[!] Missing dependencies:\n")
        for d in missing:
            print(f"  {d['name']:<12}  install: {d['install_cmd']}")
        print()
        sys.exit(1)

    if not headless:
        import os
        if args.live:
            os.environ["SCRUTICS_AUTO_LIVE"]     = args.live
            os.environ["SCRUTICS_AUTO_DURATION"] = str(args.duration)
            os.environ["SCRUTICS_AUTO_BASELINE"] = str(args.baseline)
            os.environ["SCRUTICS_AUTO_OUTPUT"]   = args.output
        elif args.file:
            os.environ["SCRUTICS_AUTO_FILE"]   = args.file
            os.environ["SCRUTICS_AUTO_OUTPUT"] = args.output
        from scrutics.ui.tui import run
        run()
    else:
        sys.exit(run_headless(args))


if __name__ == "__main__":
    main()
