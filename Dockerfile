FROM ubuntu:24.04

# Install 32-bit support
RUN dpkg --add-architecture i386

ENV TZ=Asia/Taipei

# Update and install all dependencies in one layer to minimize issues
RUN DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing && \
    apt-get install -y --fix-missing --no-install-recommends \
    tzdata \
    git \
    build-essential \
    python3 \
    python3-dev \
    python3-venv \
    python3-pip \
    curl \
    ca-certificates \
    libssl-dev \
    nasm \
    binutils-multiarch \
    libtool \
    libreadline-dev \
    cmake \
    libffi-dev \
    libxslt1-dev \
    libxml2-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install 32-bit libraries separately (these can fail on some systems)
RUN DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing && \
    apt-get install -y --fix-missing --no-install-recommends \
    zlib1g:i386 \
    libtinfo6:i386 \
    libstdc++6:i386 \
    libgcc-s1:i386 \
    libc6:i386 \
    || true && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# MinGW for compiling test drivers
RUN DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
    mingw-w64 \
    gcc-mingw-w64-x86-64 \
    g++-mingw-w64-x86-64 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup user `ioctlance` with a home directory
RUN useradd -ms /bin/bash ioctlance

# Create working directory and set permissions
WORKDIR /home/ioctlance/app
RUN chown -R ioctlance:ioctlance /home/ioctlance

# Switch to ioctlance user for all Python/uv setup
USER ioctlance

# Install uv package manager for ioctlance user
ENV UV_LINK_MODE=copy
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Add uv to PATH for this user
ENV PATH="/home/ioctlance/.local/bin:$PATH"

# Copy project files
COPY --chown=ioctlance:ioctlance pyproject.toml uv.lock /home/ioctlance/app/
COPY --chown=ioctlance:ioctlance src/ /home/ioctlance/app/src/
COPY --chown=ioctlance:ioctlance samples/ /home/ioctlance/app/samples/
COPY --chown=ioctlance:ioctlance tests/ /home/ioctlance/app/tests/
COPY --chown=ioctlance:ioctlance test_drivers/ /home/ioctlance/app/test_drivers/
COPY --chown=ioctlance:ioctlance README.md License.txt /home/ioctlance/app/

# Install dependencies with uv
RUN cd /home/ioctlance/app && \
    uv sync --frozen

# Set working directory
WORKDIR /home/ioctlance/app

# Default command - run IOCTLance CLI
CMD ["uv", "run", "python", "-m", "ioctlance.cli", "--help"]