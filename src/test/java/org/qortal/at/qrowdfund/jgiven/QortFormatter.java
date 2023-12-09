package org.qortal.at.qrowdfund.jgiven;

import com.tngtech.jgiven.format.ArgumentFormatter;

public class QortFormatter implements ArgumentFormatter<Object> {
    public QortFormatter() {
    }

    @Override
    public String format(Object o, String... args) {
        long qortAmount = (long) o;
        return String.format("%d.%08d QORT", qortAmount / 1_0000_0000L, qortAmount % 1_0000_0000L);
    }
}
