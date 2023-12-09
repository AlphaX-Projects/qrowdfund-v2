package org.qortal.at.qrowdfund.jgiven;

import com.tngtech.jgiven.Stage;
import com.tngtech.jgiven.annotation.ExpectedScenarioState;
import com.tngtech.jgiven.annotation.ProvidedScenarioState;
import com.tngtech.jgiven.annotation.ScenarioState;
import org.ciyam.at.API;
import org.ciyam.at.test.ExecutableTest;
import org.ciyam.at.test.TestAPI;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import static org.junit.Assert.*;

public class QrowdfundThen extends Stage<QrowdfundThen> {
    @ExpectedScenarioState
    ExecutableTest test;

    @ExpectedScenarioState(resolution = ScenarioState.Resolution.NAME)
    byte[] creationBytes;

    @ExpectedScenarioState
    Long goal;

    @ExpectedScenarioState
    TestAPI.TestAccount  awardee;

    @ExpectedScenarioState
    List<TestAPI.TestAccount> donors;

    @ExpectedScenarioState
    Map<TestAPI.TestAccount, Long> donationsByDonor;

    @ProvidedScenarioState
    List<TestAPI.TestTransaction> atPayments;

    public QrowdfundThen creation_bytes_exist() {
        assertNotNull(creationBytes);
        assertTrue(creationBytes.length > 0);
        return self();
    }

    public QrowdfundThen AT_is_sleeping() {
        assertTrue(test.state.isSleeping());
        return self();
    }

    public QrowdfundThen AT_is_finished() {
        assertTrue(test.state.isFinished());
        return self();
    }

    public QrowdfundThen no_donations_received() {
        Optional<TestAPI.TestTransaction> maybeTransaction = test.api.atTransactions.stream()
                .filter(transaction ->
                        transaction.txType.equals(API.ATTransactionType.PAYMENT) &&
                                transaction.recipient.equals(TestAPI.AT_ADDRESS))
                .findAny();

        assertTrue(maybeTransaction.isEmpty());
        return self();
    }

    public QrowdfundThen goal_reached() {
        long donationsTotal = donationsByDonor.values().stream().mapToLong(l -> l).sum();

        assertTrue(donationsTotal >= goal);
        return self();
    }

    public QrowdfundThen goal_not_reached() {
        long donationsTotal = donationsByDonor.values().stream().mapToLong(l -> l).sum();

        assertFalse(donationsTotal >= goal);
        return self();
    }

    public QrowdfundThen AT_sent_payments() {
        // Find AT PAYMENT
        atPayments = test.api.atTransactions.stream()
                .filter(transaction ->
                        transaction.txType.equals(API.ATTransactionType.PAYMENT) &&
                                transaction.sender.equals(TestAPI.AT_ADDRESS))
                .collect(Collectors.toList());

        assertFalse(atPayments.isEmpty());

        return self();
    }

    public QrowdfundThen creator_is_refunded() {
        assertNotNull(atPayments);
        assertEquals(1, atPayments.size());
        assertEquals(TestAPI.AT_CREATOR_ADDRESS, atPayments.get(0).recipient);
        return self();
    }

    public QrowdfundThen awardee_is_recipient() {
        assertNotNull(atPayments);
        assertTrue(atPayments.size() >= 1);
        assertEquals(awardee.address, atPayments.get(0).recipient);
        assertTrue(atPayments.get(0).amount >= goal);
        return self();
    }

    public QrowdfundThen donors_are_refunded() {
        assertNotNull(atPayments);

        // collate payments sent by AT
        Map<String, Long> refundsByRecipient = new HashMap<>();
        atPayments.stream().forEach(payment -> refundsByRecipient.merge(payment.recipient, payment.amount, Long::sum));

        // check against donations
        donationsByDonor.entrySet().stream().forEach(donation -> assertEquals(donation.getValue(), refundsByRecipient.get(donation.getKey().address)));

        // we're not concerned with leftover sent by to creator

        return self();
    }
}
