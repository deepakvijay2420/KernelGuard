#!/usr/bin/env python3

ALLOWED = {
    "research_agent_01": {
        "/usr/bin/ls",
        "/usr/bin/cat",
        "/usr/bin/date",
        "/usr/bin/whoami"
    }
}

BLOCKED = {
    "research_agent_01": {
        "/usr/bin/sudo",
        "/bin/bash",
        "/bin/sh"
    }
}


def check_policy(agent_id, executable):

    if executable in BLOCKED.get(agent_id, set()):
        return "DENY"

    if executable in ALLOWED.get(agent_id, set()):
        return "ALLOW"

    return "REVIEW"


if __name__ == "__main__":

    tests = [
        "/usr/bin/ls",
        "/usr/bin/cat",
        "/usr/bin/sudo",
        "/bin/bash",
        "/usr/bin/unknown"
    ]

    for command in tests:
        print(
            command,
            "->",
            check_policy("research_agent_01", command)
        )
