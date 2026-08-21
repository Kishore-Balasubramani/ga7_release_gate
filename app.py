from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/release-gate", methods=["POST"])
def release_gate():
    data = request.get_json()

    violations = []

    workflow = data.get("workflow", {})
    permissions = workflow.get("permissions", {})
    image = data.get("image", {})

    # 1. Permissions
    if permissions != {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }:
        violations.append("EXCESS_PERMISSION")

    # 2. PR trigger
    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests / matrix / failFast
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner != "actions":
            if not (
                len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Image checks
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production checks
    if data.get("target") == "production":
        if not (
            data.get("event") == "push"
            and data.get("ref") == "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return jsonify({
        "decision": "promote" if not violations else "block",
        "violations": violations
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)