import re
from .history.logs import my_get_changelog, rst_changelog
from .settings import config

version_reg = r'\d{1,3}(?:.\d{1,3})*'


def update_setup_py(new_version):

    setup_py = config.get('semantic_release', 'setup_py')
    with open(setup_py, mode='r') as fr:
        content = fr.read()

    content = re.sub(r'version ?= ?["\']({version})["\']'.format(version=version_reg),
                     r"version='{0}'".format(new_version),
                     content
                     )
    content = re.sub(r'(download_url ?= ?.+archive\/v?){version}(\.tar\.gz)'.format(version=version_reg),
                     r'\g<1>{}\g<2>'.format(new_version),
                     content
                     )

    with open(setup_py, mode='w') as fw:
        fw.write(content)
    return True


def update_changelog_rst(from_version, new_version, date, section='Changelog'):
    changelog_file = config.get('semantic_release', 'changelog_rst')
    with open(changelog_file, mode='r') as fr:
        content = fr.read()

    section_directive = '=' * len(section)
    changelog_dict = my_get_changelog(from_version)
    changelog_rst_string = rst_changelog(new_version, changelog_dict, date)
    content = re.sub(r'({section}\n{section_directive})\n+(v?{version})'.format(section=section, section_directive=section_directive, version=version_reg),
                     r'\g<1>\n\n{}\n\n\g<2>'.format(changelog_rst_string),
                     content
                     )

    with open(changelog_file, mode='w') as fw:
        fw.write(content)
    return True


def update_readme(from_version, new_version):
    """Call this method to update potentially found diff strings (ie compare/v1.2.1...master, compare/v1.4..dev) and paths to svg images (ie v1.2.1.svg) in readme.rst\n
        Limitations: only supports diff strings comparing either to 'master' or 'dev' branches
    """

    readme_file = config.get('semantic_release', 'readme_rst')
    with open(readme_file, mode='r') as fr:
        content = fr.read()
    
    content = re.sub(r'v{old_version}.svg'.format(old_version=from_version),
                     r'v{new_version}.svg'.format(new_version=new_version),
                     content
                     )

    content = re.sub(r'compare/v{old_version}(...?)(master|dev)'.format(old_version=from_version),
                     r'compare/v{new_version}\g<1>\g<2>'.format(new_version=new_version),
                     content
                     )

    with open(readme_file, mode='w') as fw:
        fw.write(content)
    return True
