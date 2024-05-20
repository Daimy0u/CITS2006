import sys
from tests import yara
from modules.yara_engine.Engine import YaraEngine


yara.run('./modules/lib/yara_engine/rules/base/base.yar','./modules/lib/yara_engine/test',)
