
clean:
	@rm -rf dist/*
dist: clean
	python3 setup.py sdist bdist_wheel

publish:
	twine upload dist/*