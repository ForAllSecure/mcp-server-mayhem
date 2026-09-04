import typer

app = typer.Typer()


@app.command()
def version():
    from mcp_server_mayhem.server import version as server_version
    import asyncio
    print(asyncio.run(server_version()))


@app.command()
def mcp():
    from mcp_server_mayhem.server import main as server_main
    server_main()


if __name__ == "__main__":
    app()