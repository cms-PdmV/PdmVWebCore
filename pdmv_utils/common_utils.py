"""
Common utils
"""

def clean_split(string, separator=','):
    """
    Split a string by separator and collect only non-empty values
    """
    return [x.strip() for x in string.split(separator) if string.strip()]

def cmssw_setup(cmssw_release):
    """
    Return code needed to set up CMSSW environment for given CMSSW release
    Basically, cmsrel and cmsenv commands
    """
    commands = ['source /cvmfs/cms.cern.ch/cmsset_default.sh',
                f'if [ -r {cmssw_release}/src ] ; then echo {cmssw_release} already exist',
                f'else scram p CMSSW {cmssw_release}',
                'fi',
                f'cd {cmssw_release}/src',
                'eval `scram runtime -sh`',
                'cd ../..']
    return '\n'.join(commands)
