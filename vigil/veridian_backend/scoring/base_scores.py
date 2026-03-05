BASE_SCORES: dict[str, int] = {
    "RULE_1A": 35,  # SI/FN Modified — common, moderate weight
    "RULE_1B": 45,  # SI/FN Created  — rarer, higher weight
    "RULE_2": 55,  # Logical impossibility — very high weight
    "RULE_3": 40,  # USN timestamp rollback
    "RULE_4": 35,  # Metadata suppression
    "RULE_5": 50,  # LSN missing from active log
    "RULE_6": 60,  # LSN wrong file — highest base score
    "RULE_7": 40,  # LogFile timestamp rollback
    "RULE_8": 45,  # LSN order violation
    "RULE_9": 50,  # USN sequence gap
}

