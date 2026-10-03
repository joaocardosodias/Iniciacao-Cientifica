from prompts.wannacry import PROMPT as WANNACRY
from prompts.eternalblue import PROMPT as ETERNALBLUE
from prompts.worm import PROMPT as WORM

PROMPTS = {
    "wannacry": WANNACRY,
    "eternalblue": ETERNALBLUE,
    "worm": WORM,
}

__all__ = ["PROMPTS"]
