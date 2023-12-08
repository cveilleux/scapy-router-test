import setuptools

setuptools.setup(
    name='router_test',
    version='0.1.0',
    packages=setuptools.find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'router-test = router_test.__main__:main'
        ]
    },
)
