"""PromptArmor command line interface (typer + rich)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from promptarmor import __version__
from promptarmor.config import ConfigError, load_target_config
from promptarmor.pack import PackError, load_pack
from promptarmor.runner import AttackResult, run_pack

app = typer.Typer(
    name="promptarmor",
    help=(
        "Security testing harness for LLMs. Runs curated attack prompts "
        "against a target model and reports which ones got through. "
        "Only test models you own or have permission to test."
    ),
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

_VERDICT_STYLE = {"PASS": "bold green", "FAIL": "bold red", "ERROR": "bold yellow"}
_SEVERITY_STYLE = {
    "low": "cyan",
    "medium": "yellow",
    "high": "dark_orange",
    "critical": "bold red",
}


@app.command()
def version() -> None:
    """Print the PromptArmor version."""
    console.print(f"PromptArmor v{__version__}")


@app.command()
def packs() -> None:
    """List attacks in the built-in core pack."""
    pack = load_pack("core")
    table = Table(title=f"Pack '{pack.name}': {len(pack.attacks)} attacks")
    table.add_column("ID", style="bold")
    table.add_column("Category")
    table.add_column("OWASP")
    table.add_column("Severity")
    table.add_column("Title")
    for attack in pack.attacks:
        table.add_row(
            attack.id,
            attack.category,
            attack.owasp,
            f"[{_SEVERITY_STYLE.get(attack.severity, '')}]{attack.severity}[/]",
            attack.title,
        )
    console.print(table)


@app.command()
def run(
    target: Path = typer.Option(
        ..., "--target", "-t", help="Path to the target config YAML file."
    ),
    pack_name: str = typer.Option(
        "core", "--pack", "-p", help="Built-in pack name or path to a pack YAML."
    ),
    show_responses: bool = typer.Option(
        False, "--show-responses", help="Print each model response in full."
    ),
) -> None:
    """Run an attack pack against a target model and print the scorecard."""
    try:
        config = load_target_config(target)
        pack = load_pack(pack_name)
    except (ConfigError, PackError) as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=2)

    console.print(
        Panel(
            f"Target: [bold]{config.label}[/]\n"
            f"Pack:   [bold]{pack.name}[/] ({len(pack.attacks)} attacks)\n"
            f"[dim]Reminder: only test models you own or have permission to test.[/]",
            title="PromptArmor",
            border_style="blue",
        )
    )

    def on_result(result: AttackResult) -> None:
        style = _VERDICT_STYLE[result.verdict]
        console.print(
            f"  [{style}]{result.verdict:5}[/] {result.attack.id:7} "
            f"{result.attack.category:20} {result.attack.title} "
            f"[dim]({result.duration_s:.1f}s)[/]"
        )
        if result.error:
            console.print(f"        [yellow]{result.error}[/]")
        elif show_responses and result.response:
            console.print(f"        [dim]{result.response[:400]}[/]")

    with console.status("Running attacks..."):
        run_result = run_pack(config, pack, on_result=on_result)

    table = Table(title="Category summary")
    table.add_column("Category")
    table.add_column("Resisted (PASS)", justify="right", style="green")
    table.add_column("Breached (FAIL)", justify="right", style="red")
    table.add_column("Errors", justify="right", style="yellow")
    for category, stats in sorted(run_result.by_category().items()):
        table.add_row(
            category, str(stats["PASS"]), str(stats["FAIL"]), str(stats["ERROR"])
        )
    console.print(table)

    total = len(run_result.results)
    scored = run_result.passed + run_result.failed
    rate = (run_result.passed / scored * 100) if scored else 0.0
    verdict_style = "green" if run_result.failed == 0 else "red"
    console.print(
        Panel(
            f"Attacks run: {total}   "
            f"[green]Resisted: {run_result.passed}[/]   "
            f"[red]Breached: {run_result.failed}[/]   "
            f"[yellow]Errors: {run_result.errored}[/]\n"
            f"Resistance rate: [{verdict_style}]{rate:.0f}%[/]",
            title="Result",
            border_style=verdict_style,
        )
    )

    if run_result.failed > 0:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
