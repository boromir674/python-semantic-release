"""Logs
"""
import re
from typing import Optional

import ndebug

from ..errors import UnknownCommitMessageStyleError
from ..settings import config, current_commit_parser
from ..vcs_helpers import get_commit_log, my_commit_log

debug = ndebug.create(__name__)

LEVELS = {
    1: 'patch',
    2: 'minor',
    3: 'major',
}

CHANGELOG_SECTIONS = [
    'feature',
    'fix',
    'breaking',
    'documentation',
    'performance',
]

re_breaking = re.compile('BREAKING CHANGE: (.*)')


def evaluate_version_bump(current_version: str, force: str = None) -> Optional[str]:
    """
    Reads git log since last release to find out if should be a major, minor or patch release.

    :param current_version: A string with the current version number.
    :param force: A string with the bump level that should be forced.
    :return: A string with either major, minor or patch if there should be a release. If no release
             is necessary None will be returned.
    """
    debug('evaluate_version_bump("{}", "{}")'.format(current_version, force))
    if force:
        return force

    bump = None

    changes = []
    commit_count = 0

    for _hash, commit_message in get_commit_log('v{0}'.format(current_version)):
        if commit_message.startswith(current_version):
            debug('"{}" is commit for {}. breaking loop'.format(commit_message, current_version))
            break
        try:
            message = current_commit_parser()(commit_message)
            changes.append(message[0])
        except UnknownCommitMessageStyleError as err:
            debug('ignored', err)
            pass

        commit_count += 1

    if changes:
        level = max(changes)
        if level in LEVELS:
            bump = LEVELS[level]
    if config.getboolean('semantic_release', 'patch_without_tag') and commit_count:
        bump = 'patch'
    return bump


def generate_changelog(from_version: str, to_version: str = None) -> dict:
    """
    Generates a changelog for the given version.

    :param from_version: The last version not in the changelog. The changelog
                         will be generated from the commit after this one.
    :param to_version: The last version in the changelog.
    :return: a dict with different changelog sections
    """
    debug('generate_changelog("{}", "{}")'.format(from_version, to_version))
    changes: dict = {
        'breaking': [],
        'documentation': [],
        'feature': [],
        'fix': [],
        'performance': [],
        'refactor': [],
    }

    found_the_release = to_version is None

    rev = None
    if from_version:
        rev = 'v{0}'.format(from_version)

    for _hash, commit_message in get_commit_log(rev):
        if not found_the_release:
            if to_version and to_version not in commit_message:
                continue
            else:
                found_the_release = True

        if from_version is not None and from_version in commit_message:
            break

        try:
            message = current_commit_parser()(commit_message)
            if message[1] not in changes:
                continue

            changes[message[1]].append((_hash, message[3][0]))

            if message[3][1] and 'BREAKING CHANGE' in message[3][1]:
                parts = re_breaking.match(message[3][1])
                if parts:
                    changes['breaking'].append((_hash, parts.group(1)))

            if message[3][2] and 'BREAKING CHANGE' in message[3][2]:
                parts = re_breaking.match(message[3][2])
                if parts:
                    changes['breaking'].append((_hash, parts.group(1)))

        except UnknownCommitMessageStyleError as err:
            debug('Ignoring', err)
            pass

    return changes


def markdown_changelog(version: str, changelog: dict, header: bool = False) -> str:
    """
    Generates a markdown version of the changelog. Takes a parsed changelog dict from
    generate_changelog.

    :param version: A string with the version number.
    :param changelog: A dict from generate_changelog.
    :param header: A boolean that decides whether a header should be included or not.
    :return: The markdown formatted changelog.
    """
    debug('markdown_changelog(version="{}", header={}, changelog=...)'.format(version, header))
    output = ''
    if header:
        output += '## v{0}\n'.format(version)

    for section in CHANGELOG_SECTIONS:
        if not changelog[section]:
            continue

        output += '\n### {0}\n'.format(section.capitalize())
        for item in changelog[section]:
            output += '* {0} ({1})\n'.format(item[1], item[0])

    return output


#############################################

def my_get_changelog(from_version: str) -> dict:
    """
    Generates a changelog from given version till HEAD.\n
    :param from_version: The last version not in the changelog. The changelog
                         will be generated from the commit after this one.
    :return: a dict with different changelog sections
    """
    debug('my_get_changelog: "{}"'.format(from_version))
    changes: dict = {
        'feature': [],
        'fix': [],
        'documentation': [],
        'refactor': [],
        'breaking': [],
        'performance': [],
        'improvement': []
    }
    debug('my_get_changelog: building changelog between previous tagged version and HEAD')

    for _hash, commit_message in my_commit_log('v{0}'.format(from_version)):
        try:
            # [level_bump [3,2,1], type [feature, fix, etc], 'scope', 'subject']
            message = current_commit_parser()(commit_message)
            if message[1] not in changes:
                continue

            changes[message[1]].append((_hash, message[3][0]))

            if message[3][1] and 'BREAKING CHANGE' in message[3][1]:
                parts = re_breaking.match(message[3][1])
                if parts:
                    changes['breaking'].append((_hash, parts.group(1)))

            if message[3][2] and 'BREAKING CHANGE' in message[3][2]:
                parts = re_breaking.match(message[3][2])
                if parts:
                    changes['breaking'].append((_hash, parts.group(1)))

        except UnknownCommitMessageStyleError as err:
            debug('Ignoring', err)
            pass

    return changes


def rst_changelog(new_version: str, changelog: dict, date: str = None, header: bool = False) -> str:
    """
    Generates an rst version of the changelog. It preserves sections\n
    - 'feature'
    - 'fix'
    - 'breaking'
    - 'documentation'
    - 'performance'

    :param str new_version: A string with the version number.
    :param dict changelog: A dict holding the items per section from generate_changelog.
    :param bool header: A boolean that decides whether a changes subsection should be included or not.
    :param str date: an optional date to include in subsection generated along with the version
    :return: The rst formatted changelog.
    """
    debug('rst_changelog(new_version="{}", header={}, changelog=...)'.format(new_version, header))
    if new_version[0] == 'v':
        new_version = new_version[1:]
    b = new_version
    if date:
        b += ' ({})'.format(date)
    b += '\n{}'.format('-'*(1+ len(b)))

    s = '^'
    if header:
        header = 'Changes'
        b += '\n\n{}\n{}'.format(header, len(header)*s)
        s = '"'
    b += '\n\n' + '\n\n'.join([get_change_type(changelog, section, s) for section in CHANGELOG_SECTIONS if changelog[section]])
    return b.strip()


def get_change_type(changelog: dict, section: str, symbol: str) -> str:
    return '{}\n{}\n{}'.format(section, len(section)*symbol, '\n'.join('- {}'.format(commit_message) for commit_hash, commit_message in changelog[section]))

#################################################