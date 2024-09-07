# Build stage
FROM ubuntu:latest AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    nlohmann-json3-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source files
COPY CMakeLists.txt .
COPY common ./common
COPY entrance_server ./entrance_server
COPY master_server ./master_server
COPY runtime_instance_server ./runtime_instance_server
COPY mock_user ./mock_user
# Install Asio
RUN wget https://github.com/chriskohlhoff/asio/archive/asio-1-28-0.tar.gz \
    && tar -xzvf asio-1-28-0.tar.gz \
    && mv asio-asio-1-28-0 asio-1-28-0 \
    && rm asio-1-28-0.tar.gz


# Build all servers
RUN mkdir build && cd build \
    && cmake .. \
    && cmake --build . --verbose

# Runtime stage
FROM ubuntu:latest

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY entrance_server_config.json /app/
COPY master_server_config.json /app/
COPY runtime_server_config.json /app/

# Copy built executables from builder stage
COPY --from=builder /app/build/bin/entrance_server /app/
COPY --from=builder /app/build/bin/master_server /app/
COPY --from=builder /app/build/bin/runtime_instance_server /app/

# Expose ports
EXPOSE 8080 8081 8082

# Set the entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create log folders
RUN mkdir -p /app/logs/master /app/logs/entrance /app/logs/runtime

ENTRYPOINT ["/app/entrypoint.sh"]