/*    */
package com.bss.entity;

import java.util.Objects;

/*    */ public class PayVo {
    private Integer payMode;
    /*    */   private Double payPoints;
    /*    */   private Double payPercent;
    /*    */   private Integer payStart;
    /*    */   private Double automaticPayment;
    /*    */   private Integer withdrawalNumber;
    /*    */   private String payChannelName;
    /*    */   private String payChannelImage;

    public PayVo(Integer payMode, Double payPoints, Double payPercent, Integer payStart, Double automaticPayment, Integer withdrawalNumber, String payChannelName, String payChannelImage) {
        /* 12 */
        this.payMode = payMode;
        this.payPoints = payPoints;
        this.payPercent = payPercent;
        this.payStart = payStart;
        this.automaticPayment = automaticPayment;
        this.withdrawalNumber = withdrawalNumber;
        this.payChannelName = payChannelName;
        this.payChannelImage = payChannelImage;
        /*    */
    }

    /*    */
    public PayVo() {
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.PayVo)) return false;
        com.bss.entity.PayVo other = (com.bss.entity.PayVo) o;
        if (!other.canEqual(this)) return false;
        Object this$payMode = getPayMode(), other$payMode = other.getPayMode();
        if (!Objects.equals(this$payMode, other$payMode)) return false;
        Object this$payPoints = getPayPoints(), other$payPoints = other.getPayPoints();
        if (!Objects.equals(this$payPoints, other$payPoints))
            return false;
        Object this$payPercent = getPayPercent(), other$payPercent = other.getPayPercent();
        if (!Objects.equals(this$payPercent, other$payPercent))
            return false;
        Object this$payStart = getPayStart(), other$payStart = other.getPayStart();
        if (!Objects.equals(this$payStart, other$payStart)) return false;
        Object this$automaticPayment = getAutomaticPayment(), other$automaticPayment = other.getAutomaticPayment();
        if (!Objects.equals(this$automaticPayment, other$automaticPayment))
            return false;
        Object this$withdrawalNumber = getWithdrawalNumber(), other$withdrawalNumber = other.getWithdrawalNumber();
        if (!Objects.equals(this$withdrawalNumber, other$withdrawalNumber))
            return false;
        Object this$payChannelName = getPayChannelName(), other$payChannelName = other.getPayChannelName();
        if (!Objects.equals(this$payChannelName, other$payChannelName))
            return false;
        Object this$payChannelImage = getPayChannelImage(), other$payChannelImage = other.getPayChannelImage();
        return !(!Objects.equals(this$payChannelImage, other$payChannelImage));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.PayVo;
    }


    public String toString() {
        return "PayVo(payMode=" + getPayMode() + ", payPoints=" + getPayPoints() + ", payPercent=" + getPayPercent() + ", payStart=" + getPayStart() + ", automaticPayment=" + getAutomaticPayment() + ", withdrawalNumber=" + getWithdrawalNumber() + ", payChannelName=" + getPayChannelName() + ", payChannelImage=" + getPayChannelImage() + ")";
    }

    /*    */
    public Integer getPayMode() {
        /* 16 */
        return this.payMode;
        /*    */
    }

    /*    */
    /* 11 */
    public void setPayMode(Integer payMode) {
        this.payMode = payMode;
    }

    public Double getPayPoints() {
        /* 18 */
        return this.payPoints;
        /*    */
    }

    public void setPayPoints(Double payPoints) {
        this.payPoints = payPoints;
    }

    public Double getPayPercent() {
        /* 20 */
        return this.payPercent;
        /*    */
    }

    public void setPayPercent(Double payPercent) {
        this.payPercent = payPercent;
    }

    public Integer getPayStart() {
        /* 22 */
        return this.payStart;
        /*    */
    }

    public void setPayStart(Integer payStart) {
        this.payStart = payStart;
    }

    public Double getAutomaticPayment() {
        /* 24 */
        return this.automaticPayment;
        /*    */
    }

    public void setAutomaticPayment(Double automaticPayment) {
        this.automaticPayment = automaticPayment;
    }

    public Integer getWithdrawalNumber() {
        /* 26 */
        return this.withdrawalNumber;
        /*    */
    }

    public void setWithdrawalNumber(Integer withdrawalNumber) {
        this.withdrawalNumber = withdrawalNumber;
    }

    public String getPayChannelName() {
        /* 28 */
        return this.payChannelName;
        /*    */
    }

    public void setPayChannelName(String payChannelName) {
        this.payChannelName = payChannelName;
    }

    public String getPayChannelImage() {
        /* 30 */
        return this.payChannelImage;
        /*    */
    }

    public void setPayChannelImage(String payChannelImage) {
        this.payChannelImage = payChannelImage;
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\PayVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */