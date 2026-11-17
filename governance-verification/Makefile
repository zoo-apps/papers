# Zoo Governance Verification Makefile

.PHONY: test build

test:
	@echo "Running machine-checked invariant tests..."
	opa test ./policy/ -v

paper:
	TEXINPUTS=".:..:" latexmk -pdf governance-verification.tex

all: test paper
