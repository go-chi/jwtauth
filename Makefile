SHELL            = bash -o pipefail
TEST_FLAGS       ?= -v -race

all:
	@echo "make <cmd>"
	@echo ""
	@echo "commands:"
	@echo ""
	@echo " + Development:"
	@echo "   - build"
	@echo "   - test"
	@echo "   - todo"
	@echo "   - clean"
	@echo ""
	@echo ""


##
## Development
##
build:
	go build ./...

clean:
	go clean -cache -testcache

test: test-clean
	GOGC=off go test $(TEST_FLAGS) -run=$(TEST) ./...

test-clean:
	GOGC=off go clean -testcache

bench:
	@go test -timeout=25m -bench=.

todo:
	@git grep TODO -- './*' ':!./vendor/' ':!./Makefile' || :
