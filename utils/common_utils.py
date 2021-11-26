"""
Common utils
"""
import re
import json
import xml.etree.ElementTree as XMLet
from ..utils.cache import TimeoutCache
from ..utils.connection_wrapper import ConnectionWrapper
from ..utils.locker import Locker
from ..utils.global_config import Config


# Scram arch cache to save some requests to cmssdt.cern.ch
__scram_arch_cache = TimeoutCache(3600)


def clean_split(string, separator=',', maxsplit=-1):
    """
    Split a string by separator and collect only non-empty values
    """
    return [x.strip() for x in string.split(separator, maxsplit) if x.strip()]


def make_regex_matcher(pattern):
    """
    Compile a regex pattern and return a function that performs fullmatch on
    given value
    """
    compiled_pattern = re.compile(pattern)
    def matcher_function(value):
        """
        Return whether given value fully matches the pattern
        """
        return compiled_pattern.fullmatch(value) is not None

    return matcher_function


def cmssw_setup(cmssw_release, scram_arch=None):
    """
    Return code needed to set up CMSSW environment for given CMSSW release
    Basically, cmsrel and cmsenv commands
    If reuse is set to True, this will checkout CMSSW in parent directory
    If scram_arch is None, use default arch of CMSSW release
    Releases are put to <scram arch>/<release name> directory
    """
    if scram_arch is None:
        scram_arch = get_scram_arch(cmssw_release)

    if not scram_arch:
        raise Exception(f'Could not find SCRAM arch of {cmssw_release}')

    commands = [f'export SCRAM_ARCH={scram_arch}',
                'source /cvmfs/cms.cern.ch/cmsset_default.sh',
                'ORG_PWD=$(pwd)',
                f'mkdir -p {scram_arch}',
                f'cd {scram_arch}',
                f'if [ ! -r {cmssw_release}/src ] ; then scram p CMSSW {cmssw_release} ; fi',
                f'cd {cmssw_release}/src',
                'CMSSW_SRC=$(pwd)',
                'eval `scram runtime -sh`',
                'cd $ORG_PWD']

    return '\n'.join(commands)


def config_cache_lite_setup():
    """
    Return code needed to set up ConfigCacheLite and TweakMakerLite
    """
    commands = []
    repo = 'https://github.com/cms-PdmV/ConfigCacheLite.git'
    commands += [f'if [ ! -r ConfigCacheLite ] ; then git clone --quiet {repo} ; fi',
                 'export PYTHONPATH=$(pwd)/ConfigCacheLite/:$PYTHONPATH']
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


def dbs_datasetlist(query):
    """
    Query DBS datasetlist endpoint with a query of list of datasets
    List of datasets do not support wildcards
    String query supports wildcards
    """
    if not query:
        return []

    grid_cert = Config.get('grid_user_cert')
    grid_key = Config.get('grid_user_key')
    dbs_conn = ConnectionWrapper(host='cmsweb-prod.cern.ch',
                                 port=8443,
                                 cert_file=grid_cert,
                                 key_file=grid_key)

    if isinstance(query, list):
        query = [ds[ds.index('/'):] for ds in query]
    else:
        query = query[query.index('/'):]

    dbs_response = dbs_conn.api('POST',
                                '/dbs/prod/global/DBSReader/datasetlist',
                                {'dataset': query,
                                 'detail': 1})
    dbs_response = json.loads(dbs_response.decode('utf-8'))
    if not dbs_response:
        return []

    return dbs_response
