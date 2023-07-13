# requires this collection to be in a directory following this path convention:
# some_dir/ansible_collections/puzzle/opnsense
COLLECTION_PATH=$(realpath ../../../):~/.ansible/collections:/usr/share/ansible/collections

build-doc:
	rm -rf dest && mkdir --mode 0700 dest && \
	ANSIBLE_COLLECTIONS_PATHS=${COLLECTION_PATH} antsibull-docs sphinx-init --use-current --dest-dir dest puzzle.opnsense > /dev/null && \
	cd dest && \
	pip install -r requirements.txt >/dev/null && ANSIBLE_COLLECTIONS_PATHS=${COLLECTION_PATH} ./build.sh ; \
	echo "\n\nTo view the built doc page visit file://$$PWD/build/html/index.html in a browser of your choice\n\n"

test-unit:
	pipenv run ansible-test units --coverage --docker

# runs a little faster because only one version is checked
test-unit-dev:
	pipenv run ansible-test units --coverage --python 3.10

test-sanity:
	pipenv run ansible-test sanity --docker

test-coverage-report:
	pipenv run ansible-test coverage report

test: test-sanity test-unit test-coverage-report
