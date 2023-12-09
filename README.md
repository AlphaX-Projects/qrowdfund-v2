`# Qrowdfund v2.0.0

## How to build

`mvn clean`
`mvn package`
`mvn install dependency:copy-dependencies`

## How to use

For usage:\
    `java -cp 'target/qrowdfund-2.0.0.jar:target/dependency/*' org.qortal.at.qrowdfund.Qrowdfund`

Example use:\
    `java -cp 'target/qrowdfund-2.0.0.jar:target/dependency/*' org.qortal.at.qrowdfund.Qrowdfund 60 10.4 QdSnUy6sUiEnaN87dWmE92g1uQjrvPgrWG`

Produces AT creation bytes:\
    `1Pub6o13xyqfCZj8BMzmXsREVJR6h4xxpS2VPV1R2QwjP78r2ozxsNuvb28GWrT8FoTTQMGnVP7pNii6auUqYr2uunWfcxwhERbDgFdsJqtrJMpQNGB9GerAXYyiFiij35cP6eHw7BmALb3viT6VzqaXX9YB25iztekV5cTreJg7o2hRpFc9Rv8Z9dFXcD1Mm4WCaMaknUgchDi7qDnHA7JX8bn9EFD4WMG5nZHMsrmeqBHirURXr2dMxFprTBo187zztmw7vDeNpzeZsc1nmQMGvGFmsuWvb7GJ4sbWGahd9CFcmUA5YqqHnB2VYBuGkZtsYsAt8PvwPRCp5cNsoN6gZGdwNnuToNsBmfAtN3FF3L4BCf78WsmYuzrua6MYyxjN6xBWQ21nG7L1LpZwsVH`

Creation bytes can be passed to `qort-tx` script as part of a `DEPLOY-AT` transaction:\
    `qort-tx DEPLOY_AT <privkey> <name> <description> <aTType> <tags> <creationBytes> <amount>`

So using example above, sending 1.0 QORT to cover AT fees:\
    `description="qrowdfund test 60min, 10.4 QORT to null account awardee"`\
    `creation_bytes=$(java -cp 'target/qrowdfund-2.0.0.jar:target/dependency/*' org.qortal.at.qrowdfund.Qrowdfund 60 10.4 QdSnUy6sUiEnaN87dWmE92g1uQjrvPgrWG | tail +2)`\
    `qort-tx -s -p DEPLOY_AT private-key-in-base58 'qrowdfund-test' "$description" 'qrowdfund' 'qrowdfund' $creation_bytes 1.0`
