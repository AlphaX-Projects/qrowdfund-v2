package org.qortal.at.qrowdfund.jgiven;

import com.tngtech.jgiven.Stage;
import com.tngtech.jgiven.annotation.As;
import com.tngtech.jgiven.annotation.ExpectedScenarioState;
import com.tngtech.jgiven.annotation.ProvidedScenarioState;
import com.tngtech.jgiven.annotation.ScenarioState;
import org.ciyam.at.MachineState;
import org.ciyam.at.test.ExecutableTest;
import org.ciyam.at.test.TestAPI;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

// Heavily based on org.ciyam.at.test.ExecutableTest
public class QrowdfundWhen extends Stage<QrowdfundWhen> {
    private static final Random RANDOM = new Random();

    @ExpectedScenarioState
    ExecutableTest test;

    @ExpectedScenarioState(resolution = ScenarioState.Resolution.NAME)
    byte[] creationBytes;

    @ExpectedScenarioState
    List<TestAPI.TestAccount> donors;

    @ProvidedScenarioState
    Map<TestAPI.TestAccount, Long> donationsByDonor = new HashMap<>();

    public QrowdfundWhen deploy_qrowdfund() {
        System.out.println("First execution - deploying...");
        test.state = new MachineState(test.api, test.loggerFactory, creationBytes);
        test.codeBytes = test.state.getCodeBytes();
        test.packedState = test.state.toBytes();

        return self();
    }

    public QrowdfundWhen execute_once() {
        test.execute_once();

        return self();
    }

    public QrowdfundWhen execute_until_finished() {
        do {
            test.execute_once();
        } while (!test.state.isFinished());

        return self();
    }

    @As("random donor sends random payment")
    public QrowdfundWhen send_payment() {
        // Generate tx hash
        byte[] txHash = new byte[32];
        RANDOM.nextBytes(txHash);

        long amount = RANDOM.nextInt(1_000_000);

        TestAPI.TestAccount donor = donors.get(RANDOM.nextInt(donors.size()));
        donationsByDonor.merge(donor, amount, Long::sum);

        TestAPI.TestTransaction testTransaction = new TestAPI.TestTransaction(txHash, donor.address, TestAPI.AT_ADDRESS, amount);
        test.api.addTransactionToCurrentBlock(testTransaction);

        return self();
    }

    @As("random donor sends payment of $2")
    public QrowdfundWhen send_payment(@QortAmount long amount) {
        // Generate tx hash
        byte[] txHash = new byte[32];
        RANDOM.nextBytes(txHash);

        TestAPI.TestAccount donor = donors.get(RANDOM.nextInt(donors.size()));
        donationsByDonor.merge(donor, amount, Long::sum);

        TestAPI.TestTransaction testTransaction = new TestAPI.TestTransaction(txHash, donor.address, TestAPI.AT_ADDRESS, amount);
        test.api.addTransactionToCurrentBlock(testTransaction);

        return self();
    }

    @As("donor $1 sends payment of $2")
    public QrowdfundWhen send_payment(int donorIndex, @QortAmount long amount) {
        // Generate tx hash
        byte[] txHash = new byte[32];
        RANDOM.nextBytes(txHash);

        TestAPI.TestAccount donor = donors.get(donorIndex);
        donationsByDonor.merge(donor, amount, Long::sum);

        TestAPI.TestTransaction testTransaction = new TestAPI.TestTransaction(txHash, donor.address, TestAPI.AT_ADDRESS, amount);
        test.api.addTransactionToCurrentBlock(testTransaction);

        return self();
    }
}
