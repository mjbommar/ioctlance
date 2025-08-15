FROM ubuntu:24.04

# install 32-bit support
RUN dpkg --add-architecture i386

ENV TZ=Asia/Taipei

# Update and install tzdata non-interactively
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# general dependencies - updated for Ubuntu 24.04
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    python3 \
    python3-dev \
    python3-venv \
    curl \
    ca-certificates \
    htop \
    vim \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# angr dependencies - updated for Ubuntu 24.04
# Note: openjdk-8-jdk is no longer available in 24.04, using openjdk-17-jdk instead
# libgcc1 is now libgcc-s1
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    zlib1g:i386 \
    libtinfo6:i386 \
    libstdc++6:i386 \
    libgcc-s1:i386 \
    libc6:i386 \
    libssl-dev \
    nasm \
    binutils-multiarch \
    qtdeclarative5-dev \
    libpixman-1-dev \
    libglib2.0-dev \
    debian-archive-keyring \
    debootstrap \
    libtool \
    libreadline-dev \
    cmake \
    libffi-dev \
    libxslt1-dev \
    libxml2-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# setup user `ioctlance` with a home directory
RUN useradd -ms /bin/bash ioctlance

# Create working directory and set permissions
WORKDIR /home/ioctlance
RUN chown -R ioctlance:ioctlance /home/ioctlance

# Switch to ioctlance user for all Python/uv setup
USER ioctlance

# Install uv package manager for ioctlance user
ENV UV_LINK_MODE=copy
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Add uv to PATH for this user
ENV PATH="/home/ioctlance/.local/bin:$PATH"

# Create virtual environment and install Python dependencies using uv
# Need --prerelease=allow for unicorn==1.0.2rc4 dependency
# Upgraded to latest angr (9.2.170) with compatible dependencies
RUN uv venv /home/ioctlance/.venv && \
    uv pip install --prerelease=allow \
    angr==9.2.170 \
    ipython \
    ipdb \
    capstone

# Set environment to use the virtual environment
ENV PATH="/home/ioctlance/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/home/ioctlance/.venv"

# Copy project files
COPY --chown=ioctlance:ioctlance ./analysis /home/ioctlance/analysis/
COPY --chown=ioctlance:ioctlance ./evaluation /home/ioctlance/evaluation/
COPY --chown=ioctlance:ioctlance ./dataset /home/ioctlance/dataset/

WORKDIR /home/ioctlance/
CMD ["/bin/bash"]