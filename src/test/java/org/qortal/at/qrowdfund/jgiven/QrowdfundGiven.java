package org.qortal.at.qrowdfund.jgiven;

import com.tngtech.jgiven.Stage;
import com.tngtech.jgiven.annotation.As;
import com.tngtech.jgiven.annotation.ProvidedScenarioState;
import com.tngtech.jgiven.annotation.ScenarioState;
import org.ciyam.at.AtLoggerFactory;
import org.ciyam.at.test.ExecutableTest;
import org.ciyam.at.test.QuietTestLoggerFactory;
import org.ciyam.at.test.TestAPI;
import org.ciyam.at.test.TestLoggerFactory;
import org.qortal.at.qrowdfund.Qrowdfund;
import org.qortal.utils.Base58;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class QrowdfundGiven extends Stage<QrowdfundGiven> {
    @ProvidedScenarioState
    ExecutableTest test;

    @ProvidedScenarioState(resolution = ScenarioState.Resolution.NAME)
    byte[] creationBytes;

    @ProvidedScenarioState
    AtLoggerFactory loggerFactory = new TestLoggerFactory();

    @ProvidedScenarioState
    Long goal;

    @ProvidedScenarioState
    TestAPI.TestAccount awardee;

    @ProvidedScenarioState
    List<TestAPI.TestAccount> donors;

    @As("fresh qrowdfund ($1 minute sleep, $2 goal)")
    public QrowdfundGiven fresh_qrowdfund(int sleepMinutes, @QortAmount long goalAmount) {
        test = new ExecutableTest();
        test.loggerFactory = loggerFactory;
        test.api = new TestAPI(); // new blockchain

        awardee = new TestAPI.TestAccount("QawardeeQQQQQQQQQQQQQQQQQQQQNPoZ8C", 0L);
        awardee.addToMap(test.api.accounts);

        creationBytes = Qrowdfund.buildQortalAT(sleepMinutes, goalAmount, awardee.address);
        goal = goalAmount;

        // Create several potential donors
        donors = new ArrayList<>();

        for (int i = 0; i < 20; ++i) {
            String address = String.format("Q_donor_%02d", i);
            TestAPI.TestAccount donor = new TestAPI.TestAccount(address, 100_0000_0000L);
            donor.addToMap(test.api.accounts);
            donors.add(donor);
        }

        return self();
    }

    public QrowdfundGiven quiet_logger() {
        loggerFactory = new QuietTestLoggerFactory();

        return self();
    }
}
