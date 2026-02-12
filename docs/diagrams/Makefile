MMDC = mmdc

MERMAID_FILES := $(wildcard *.mermaid)
SVG_FILES := $(MERMAID_FILES:.mermaid=.svg)

all: $(SVG_FILES)

%.svg: %.mermaid
	mmdc -q -i $< -o $@

clean:
	rm -f $(SVG_FILES)
