"""
Common utils
"""
import xml.etree.ElementTree as XMLet
from ..utils.cache import TimeoutCache
from ..utils.connection_wrapper import ConnectionWrapper
from ..utils.locker import Locker

# Scram arch cache to save some requests to cmssdt.cern.ch
__scram_arch_cache = TimeoutCache(3600)


def clean_split(string, separator=','):
    """
    Split a string by separator and collect only non-empty values
    """
    return [x.strip() for x in string.split(separator) if x.strip()]


def cmssw_setup(cmssw_release, reuse=False, scram_arch=None):
    """
    Return code needed to set up CMSSW environment for given CMSSW release
    Basically, cmsrel and cmsenv commands
    If reuse is set to True, this will checkout CMSSW in parent directory
    If scram_arch is None, use default arch of CMSSW release
    """
    if scram_arch is None:
        scram_arch = get_scram_arch(cmssw_release)

    commands = [f'export SCRAM_ARCH={scram_arch}',
                'source /cvmfs/cms.cern.ch/cmsset_default.sh',
                'ORG_PWD=$(pwd)']
    if reuse:
        commands += ['cd ..']

    commands += [f'if [ ! -r {cmssw_release}/src ] ; then scram p CMSSW {cmssw_release} ; fi',
                 f'cd {cmssw_release}/src',
                 'CMSSW_SRC=$(pwd)',
                 'eval `scram runtime -sh`',
                 'cd $ORG_PWD']

    return '\n'.join(commands)


def config_cache_lite_setup(reuse_files=False):
    """
    Return code needed to set up ConfigCacheLite and TweakMakerLite
    """
    commands = []
    repo = 'https://github.com/cms-PdmV/ConfigCacheLite.git'
    if reuse_files:
        commands += ['ORG_PWD=$(pwd)',
                     'cd ..']

    commands += [f'if [ ! -r ConfigCacheLite ] ; then git clone --quiet {repo} ; fi',
                 'export PYTHONPATH=$(pwd)/ConfigCacheLite/:$PYTHONPATH']

    if reuse_files:
        commands += ['cd $ORG_PWD']

    return '\n'.join(commands)


def get_scram_arch(cmssw_release):
    """
    Get scram arch from
    https://cmssdt.cern.ch/SDT/cgi-bin/ReleasesXML?anytype=1
    Cache it global variable
    """
    if not cmssw_release:
        return None

    cached_releases = __scram_arch_cache.get('releases', {})
    cached_value = cached_releases.get(cmssw_release)
    if cached_value:
        return cached_value

    with Locker().get_lock('get-scram-arch'):
        # Maybe cache got updated while waiting for a lock
        cached_releases = __scram_arch_cache.get('releases', {})
        cached_value = cached_releases.get(cmssw_release)
        if cached_value:
            return cached_value

        connection = ConnectionWrapper(host='cmssdt.cern.ch')
        response = connection.api('GET', '/SDT/cgi-bin/ReleasesXML?anytype=1')
        root = XMLet.fromstring(response)
        releases = {}
        for architecture in root:
            if architecture.tag != 'architecture':
                # This should never happen as children should be <architecture>
                continue

            scram_arch = architecture.attrib.get('name')
            for release in architecture:
                releases[release.attrib.get('label')] = scram_arch

        __scram_arch_cache.set('releases', releases)

    return releases.get(cmssw_release)
