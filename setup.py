import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='scrapy-dynamic-sessions',

    version='0.0.1',

    description='A session-management extension with random proxies and User-Agents for Scrapy.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',

    author='Dmitry Kanarsky',
    author_email='dkanarsky@gmail.com',

    url='https://github.com/DKanarsky/scrapy-dynamic-sessions',
    packages=[
        'scrapy_dynamic_sessions',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: Scrapy',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        'Topic :: Internet :: WWW/HTTP',
    ],
    install_requires=[
        'fake-useragent',
        'faker',
    ],
)