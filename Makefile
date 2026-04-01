# Makefile for Zoo Papers
# Auto-discovers all .tex files and compiles to pdfs/

TEX_FILES := $(wildcard *.tex)
PDF_FILES := $(patsubst %.tex,pdfs/%.pdf,$(TEX_FILES))
PAPER_NAMES := $(patsubst %.tex,%,$(TEX_FILES))

.PHONY: all clean clean-all help list $(PAPER_NAMES)

all: $(PDF_FILES)
	@echo "All papers compiled."
	@ls -1 pdfs/*.pdf

pdfs:
	@mkdir -p pdfs

# Pattern rule: compile .tex -> pdfs/.pdf (three passes for refs)
pdfs/%.pdf: %.tex | pdfs
	@echo "Compiling $<..."
	@pdflatex -interaction=nonstopmode -output-directory=pdfs $< > /dev/null 2>&1 || true
	@cd pdfs && bibtex $(*F) > /dev/null 2>&1 || true
	@pdflatex -interaction=nonstopmode -output-directory=pdfs $< > /dev/null 2>&1 || true
	@pdflatex -interaction=nonstopmode -output-directory=pdfs $< > /dev/null 2>&1 || true
	@test -f pdfs/$(*F).pdf && echo "  OK $(*F).pdf" || echo "  FAIL $(*F).pdf"

# Per-paper shorthand targets (auto-generated from .tex files)
$(PAPER_NAMES): %: pdfs/%.pdf

clean:
	rm -f pdfs/*.aux pdfs/*.log pdfs/*.bbl pdfs/*.blg pdfs/*.out pdfs/*.toc pdfs/*.lof pdfs/*.lot
	rm -f *.aux *.log *.bbl *.blg *.out *.toc *.lof *.lot

clean-all: clean
	rm -f pdfs/*.pdf

list:
	@echo "Papers: $(PAPER_NAMES)" | tr ' ' '\n' | sort

help:
	@echo "Usage:"
	@echo "  make           Compile all papers"
	@echo "  make <name>    Compile one paper (e.g. make zoo-dso)"
	@echo "  make list      List all discovered papers"
	@echo "  make clean     Remove auxiliary files"
	@echo "  make clean-all Remove all generated files"
	@echo ""
	@echo "Docker build (no local texlive required):"
	@echo "  docker run --rm -v \"\$$PWD:/w\" -w /w texlive/texlive:latest make all"
