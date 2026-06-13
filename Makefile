# SPDX-License-Identifier: Apache-2.0
BMV2_SWITCH_EXE = simple_switch_grpc
TOPO_DIR ?= triangle-topo
TOPO = $(TOPO_DIR)/topology.json

include ../../utils/Makefile

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make run TOPO_DIR=triangle-topo  - Run with triangle topology (default)"
	@echo "  make run TOPO_DIR=linear-topo    - Run with linear topology (4 switches, 2 hosts)"
	@echo "  make stop                         - Stop Mininet"
	@echo "  make clean                        - Clean build artifacts and logs"
