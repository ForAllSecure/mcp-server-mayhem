# We use the Astral UV image as a base, which includes Python and UV for dependency management
FROM ghcr.io/astral-sh/uv:debian

# Install mapi and mayhem CLI
RUN curl --fail -L https://app.mayhem.security/cli/Linux/install.sh | sh

# Set up app directory
RUN mkdir /app
WORKDIR /app

# Copy only files that affect dependency resolution
COPY pyproject.toml uv.lock ./
# Install deps only (cacheable layer)
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

# Copy rest of the files and install project
COPY . .
RUN uv pip install -e .

# Install deps and run
RUN uv run mcp-server-mapi version
