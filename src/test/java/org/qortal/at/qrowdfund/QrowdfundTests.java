package org.qortal.at.qrowdfund;

import org.ciyam.at.test.TestAPI;
import org.qortal.at.qrowdfund.jgiven.AbstractQrowdfundTest;
import org.junit.Test;

import java.util.Random;

public class QrowdfundTests extends AbstractQrowdfundTest {

    private static final Random RANDOM = new Random();

    private static int DEFAULT_SLEEP_MINUTES = 10;
    private static long INITIAL_AT_FUNDING = TestAPI.DEFAULT_INITIAL_BALANCE;
    private static long DEFAULT_GOAL_AMOUNT = 20_0000_0000L; // 20 QORT

    @Test
    public void qrowdfund_should_compile() {
        given()
                .fresh_qrowdfund(DEFAULT_SLEEP_MINUTES, DEFAULT_GOAL_AMOUNT);

        then()
                .creation_bytes_exist();
    }

    @Test
    public void qrowdfund_startup() {
        given()
                .fresh_qrowdfund(DEFAULT_SLEEP_MINUTES, DEFAULT_GOAL_AMOUNT);

        when()
                .deploy_qrowdfund()
                .execute_once();

        then()
                .AT_is_sleeping();
    }

    @Test
    public void qrowdfund_refunds_creator_if_no_donations() {
        given()
                .fresh_qrowdfund(DEFAULT_SLEEP_MINUTES, DEFAULT_GOAL_AMOUNT);

        when()
                .deploy_qrowdfund()
                .execute_until_finished();

        then()
                .AT_is_finished()
                .AT_sent_payments()
                .creator_is_refunded();
    }

    @Test
    public void qrowdfund_refunds_donors_if_goal_not_reached() {
        given()
                .fresh_qrowdfund(DEFAULT_SLEEP_MINUTES, DEFAULT_GOAL_AMOUNT);

        when()
                .deploy_qrowdfund()
                .execute_once();

        when()
                .send_payment(DEFAULT_GOAL_AMOUNT / 2) // too little
                .execute_until_finished();

        then()
                .AT_is_finished()
                .AT_sent_payments()
                .donors_are_refunded();
    }

    @Test
    public void qrowdfund_pays_awardee_if_goal_reached() {
        given()
                .fresh_qrowdfund(DEFAULT_SLEEP_MINUTES, DEFAULT_GOAL_AMOUNT);

        when()
                .deploy_qrowdfund()
                .execute_once();

        when()
                .send_payment(DEFAULT_GOAL_AMOUNT)
                .execute_until_finished();

        then()
                .AT_is_finished()
                .AT_sent_payments()
                .awardee_is_recipient();
    }

    @Test
    public void multiple_donors_are_all_refunded_correctly() {
        given()
                .quiet_logger()
                .fresh_qrowdfund(DEFAULT_SLEEP_MINUTES, DEFAULT_GOAL_AMOUNT);

        when()
                .deploy_qrowdfund()
                .execute_once();

        int maxDonations = 50;

        for (int donationCount = 0; donationCount < maxDonations; ++donationCount) {
            long amount = RANDOM.nextInt((int) (DEFAULT_GOAL_AMOUNT - INITIAL_AT_FUNDING) / maxDonations / 2);

            when()
                    .send_payment(amount);
        }

        when()
                .execute_until_finished();

        then()
                .AT_is_finished()
                .AT_sent_payments()
                .donors_are_refunded();
    }

}
