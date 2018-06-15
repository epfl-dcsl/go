PAPER = main
TEX = $(wildcard *.tex)
SUBTEX = $(wildcard sections/ *.tex)
BIB = references.bib
FIGS = $(wildcard figures/*.pdf figures/*.png graphs/*.pdf graphs/*.png)

.PHONY: all clean

$(PAPER).pdf: $(TEX) $(SUBTEX) $(BIB) $(FIGS) jpaper.cls
	echo $(FIGS)
	pdflatex $(PAPER)
	bibtex $(PAPER)
	pdflatex $(PAPER)
	pdflatex $(PAPER)
	rm -f *.aux *.bbl *.blg *.log *.out
	rm -f sections/*.aux

clean:
	rm -f *.aux *.bbl *.blg *.log *.out $(PAPER).pdf
	rm -f sections/*.aux
