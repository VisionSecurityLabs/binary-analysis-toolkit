"""Terminal output helpers — colors and formatted printers."""


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


C = Colors


def heading(title: str):
    print(f"\n{C.BOLD}{C.CYAN}{'═' * 70}")
    print(f"  {title}")
    print(f"{'═' * 70}{C.RESET}")


def subheading(title: str):
    print(f"\n  {C.BOLD}{C.BLUE}── {title} ──{C.RESET}")


def warn(msg: str):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def danger(msg: str):
    print(f"  {C.RED}[!!]{C.RESET} {C.RED}{msg}{C.RESET}")


def info(msg: str):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")


def detail(label: str, value: str):
    print(f"      {C.BOLD}{label:20s}{C.RESET} {value}")
