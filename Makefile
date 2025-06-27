.PHONY: clean

clean:
	@echo "Cleaning top-level non-hidden, non-whitelisted files/directories..."
	find . -mindepth 1 -maxdepth 1 \
		! -name 'decret' \
		! -name 'examples' \
		! -name 'test-material' \
		! -name 'tests' \
		! -name 'geckodriver.log' \
		! -name 'license.txt' \
		! -name 'pylintrc' \
		! -name 'README.md' \
		! -name 'requirements.txt' \
		! -name 'requirements-minimal.txt' \
		! -name 'Makefile' \
		! -name '.*' \
		-exec rm -rf {} +

	@echo "Removing __pycache__ directories and *.pyc files from source folders..."
	find decret tests -type d -name '__pycache__' -exec rm -rf {} +
	find decret tests -type f -name '*.pyc' -delete

	@echo "Clean completed."

