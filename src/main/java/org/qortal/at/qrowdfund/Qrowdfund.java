package org.qortal.at.qrowdfund;

import org.ciyam.at.*;
import org.qortal.account.Account;
import org.qortal.account.PublicKeyAccount;
import org.qortal.crypto.Crypto;
import org.qortal.utils.Base58;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.ciyam.at.OpCode.calcOffset;

public class Qrowdfund {

    private static byte[] CODE_BYTES;

    // SHA256 of AT code bytes
    private static byte[] CODE_BYTES_HASH;

    /**
     * Returns Qortal AT creation bytes for Qrowdfund AT.
     *
     * @param sleepMinutes      Time period for allowing donations (roughly 1 block per minute)
     * @param goalAmount        Minimum goal, in QORT, to trigger award after timeout
     * @param awardee           Qortal address of awardee
     */

    public static byte[] buildQortalAT(int sleepMinutes, long goalAmount, String awardee) {
        if (sleepMinutes < 10 || sleepMinutes > 30 * 24 * 60)
            throw new IllegalArgumentException("Sleep period should be between 10 minutes and 1 month");

        if (goalAmount < 100_0000L || goalAmount > 1_000_000_00000000L)
            throw new IllegalArgumentException("Minimum amount should be between 0.01 QORT and 1,000,000 QORT");

        if (!Crypto.isValidAddress(awardee))
            throw new IllegalArgumentException("Awardee address should be a valid Qortal address");

        // Labels for data segment addresses
        int addrCounter = 0;

        final int addrSleepMinutes = addrCounter++;
        final int addrGoalAmount = addrCounter++;

        final int addrSleepUntilTimestamp = addrCounter++;
        final int addrSleepUntilHeight = addrCounter++;

        final int addrFinalAmount = addrCounter++;

        final int addrAwardeeAddress = addrCounter; addrCounter += 4;

        // Data segment
        ByteBuffer dataByteBuffer = ByteBuffer.allocate(addrCounter * MachineState.VALUE_SIZE);

        // Sleep period (minutes)
        dataByteBuffer.position(addrSleepMinutes * MachineState.VALUE_SIZE);
        dataByteBuffer.putLong(sleepMinutes);

        // Minimum accepted amount
        dataByteBuffer.position(addrGoalAmount * MachineState.VALUE_SIZE);
        dataByteBuffer.putLong(goalAmount);

        // Awardee address
        dataByteBuffer.position(addrAwardeeAddress * MachineState.VALUE_SIZE);
        dataByteBuffer.put(Base58.decode(awardee));

        // Code labels
        Integer labelPayout = null;

        ByteBuffer codeByteBuffer = ByteBuffer.allocate(768);

        // Two-pass version
        for (int pass = 0; pass < 2; ++pass) {
            codeByteBuffer.clear();

            try {
                // Initialization            

                // Use AT creation 'timestamp' as starting point for finding transactions sent to AT
                codeByteBuffer.put(OpCode.EXT_FUN_RET.compile(FunctionCode.GET_CREATION_TIMESTAMP, addrLastTxnTimestamp));

                /*
                 * We want to sleep for a while.
                 *
                 * We could use SLP_VAL but different sleep periods would produce different code hashes,
                 * which would make identifying similar qrowdfund ATs more difficult.
                 *
                 * Instead we add sleepMinutes (as block count) to current block height,
                 * which is in the upper 32 bits of current block 'timestamp',
                 * so we perform a shift-right to extract.
                 */

                // Save current block 'timestamp' into addrSleepUntilHeight
                codeByteBuffer.put(OpCode.EXT_FUN_RET.compile(FunctionCode.GET_BLOCK_TIMESTAMP, addrSleepUntilTimestamp));

                // Add number of minutes to sleep (assuming roughly 1 block per minute)
                codeByteBuffer.put(OpCode.EXT_FUN_RET_DAT_2.compile(FunctionCode.ADD_MINUTES_TO_TIMESTAMP, addrSleepUntilTimestamp, addrSleepUntilTimestamp, addrSleepMinutes));

                // Copy then shift-right to convert 'timestamp' to block height
                codeByteBuffer.put(OpCode.SET_DAT.compile(addrSleepUntilHeight, addrSleepUntilTimestamp));
                codeByteBuffer.put(OpCode.SHR_VAL.compile(addrSleepUntilHeight, 32L));

                // Sleep            
                codeByteBuffer.put(OpCode.SLP_DAT.compile(addrSleepUntilHeight));

                // Done sleeping            

                // Goal reached?
                codeByteBuffer.put(OpCode.EXT_FUN_RET.compile(FunctionCode.GET_CURRENT_BALANCE, addrFinalAmount));
                codeByteBuffer.put(OpCode.BLT_DAT.compile(addrFinalAmount, addrGoalAmount, calcOffset(codeByteBuffer, labelPayout)));

                // Goal reached - send balance to awardee

                // Load B register with awardee's address
                codeByteBuffer.put(OpCode.EXT_FUN_VAL.compile(FunctionCode.SET_B_DAT, addrAwardeeAddress));

                // Pay AT's balance to receiving address
                codeByteBuffer.put(OpCode.EXT_FUN.compile(FunctionCode.PAY_ALL_TO_ADDRESS_IN_B));

                // We're finished forever
                codeByteBuffer.put(OpCode.FIN_IMD.compile());

                labelPayout = codeByteBuffer.position();

                // Restart after this opcode (probably not needed, but just in case)
                codeByteBuffer.put(OpCode.SET_PCS.compile());

                // Load B register with awardee's address
                codeByteBuffer.put(OpCode.EXT_FUN_VAL.compile(FunctionCode.SET_B_DAT, addrAwardeeAddress));

                // Pay AT's balance to receiving address
                codeByteBuffer.put(OpCode.EXT_FUN.compile(FunctionCode.PAY_ALL_TO_ADDRESS_IN_B));

                // We're finished forever
                codeByteBuffer.put(OpCode.FIN_IMD.compile());
            } catch (CompilationException e) {
                throw new IllegalStateException("Unable to compile AT?", e);
            }
        }

        codeByteBuffer.flip();

        byte[] codeBytes = new byte[codeByteBuffer.limit()];
        codeByteBuffer.get(codeBytes);

        final short ciyamAtVersion = 2;
        final short numCallStackPages = 0;
        final short numUserStackPages = 0;
        final long minActivationAmount = 0L;

        return MachineState.toCreationBytes(ciyamAtVersion, codeBytes, dataByteBuffer.array(), numCallStackPages, numUserStackPages, minActivationAmount);
    }

    private static void usage() {
        System.err.println("usage: qrowdfund <timeout-minutes> <minimum-goal> <awardee-address>");
        System.err.println("example: qrowdfund 1440 10.4 QdSnUy6sUiEnaN87dWmE92g1uQjrvPgrWG");
        System.err.println("         deadline in 1440 mins (1 day), minimum goal 10.4 QORT");
    }

    public static void main(String[] args) {
        if (args.length != 3) {
            usage();
            System.exit(2);
        }

        int sleepMinutes;
        try {
            sleepMinutes = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            usage();
            System.err.println();
            System.err.printf("Entry window minutes '%s' invalid - should be integer larger than 10", args[0]);
            System.exit(1);
            // not reached
            throw e;
        }

        long minimumGoal;
        try {
            minimumGoal = new BigDecimal(args[1]).setScale(8).unscaledValue().longValue();
        } catch (NumberFormatException e) {
            usage();
            System.err.println();
            System.err.printf("Minimum goal '%s' invalid - should be larger than 0.1 QORT", args[1]);
            System.exit(1);
            // not reached
            throw e;
        }

        String awardee = args[2];

        if (!Crypto.isValidAddress(awardee)) {
            usage();
            System.err.println();
            System.err.printf("Awardee address '%s' not a Qortal address", awardee);
            System.exit(1);
        }

        byte[] creationBytes = buildQortalAT(sleepMinutes, minimumGoal, awardee);
        System.out.printf("Creation bytes:\n%s\n", Base58.encode(creationBytes));
    }
}