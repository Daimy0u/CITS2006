import sys
from tests import yara
from modules.yara_engine.Engine import YaraEngine


yara.run('./modules/yara_engine/rules/base/base.yar','./modules/yara_engine/test',YaraEngine)
