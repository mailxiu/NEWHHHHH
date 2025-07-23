/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.bss.enmus.WithdrawalEnum;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
/*    */
@TableName("withdrawal")
/*    */ public class Withdrawal implements Serializable {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String oid;
    /*    */   private String merchant;
    /*    */   private Integer uid;
    /*    */   private Double points;
    /*    */   private Double chargeMoney;
    /*    */   private Double realMoney;
    /*    */   private Double balance;

    /*    */
    /* 16 */
    public void setId(Integer id) {
        this.id = id;
    }

    private String alipayName;
    private String alipayAccount;
    private String paymentCode;
    private WithdrawalEnum channel;
    private String info;
    private String state;
    private String createTime;
    private static final long serialVersionUID = 1L;

    public void setOid(String oid) {
        this.oid = oid;
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setUid(Integer uid) {
        this.uid = uid;
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public void setChargeMoney(Double chargeMoney) {
        this.chargeMoney = chargeMoney;
    }

    public void setRealMoney(Double realMoney) {
        this.realMoney = realMoney;
    }

    public void setBalance(Double balance) {
        this.balance = balance;
    }

    public void setAlipayName(String alipayName) {
        this.alipayName = alipayName;
    }

    public void setAlipayAccount(String alipayAccount) {
        this.alipayAccount = alipayAccount;
    }

    public void setPaymentCode(String paymentCode) {
        this.paymentCode = paymentCode;
    }

    public void setChannel(WithdrawalEnum channel) {
        this.channel = channel;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Withdrawal)) return false;
        com.bss.entity.Withdrawal other = (com.bss.entity.Withdrawal) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$oid = getOid(), other$oid = other.getOid();
        if (!Objects.equals(this$oid, other$oid)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$chargeMoney = getChargeMoney(), other$chargeMoney = other.getChargeMoney();
        if (!Objects.equals(this$chargeMoney, other$chargeMoney))
            return false;
        Object this$realMoney = getRealMoney(), other$realMoney = other.getRealMoney();
        if (!Objects.equals(this$realMoney, other$realMoney))
            return false;
        Object this$balance = getBalance(), other$balance = other.getBalance();
        if (!Objects.equals(this$balance, other$balance)) return false;
        Object this$alipayName = getAlipayName(), other$alipayName = other.getAlipayName();
        if (!Objects.equals(this$alipayName, other$alipayName))
            return false;
        Object this$alipayAccount = getAlipayAccount(), other$alipayAccount = other.getAlipayAccount();
        if (!Objects.equals(this$alipayAccount, other$alipayAccount))
            return false;
        Object this$paymentCode = getPaymentCode(), other$paymentCode = other.getPaymentCode();
        if (!Objects.equals(this$paymentCode, other$paymentCode))
            return false;
        Object this$channel = getChannel(), other$channel = other.getChannel();
        if (!Objects.equals(this$channel, other$channel)) return false;
        Object this$info = getInfo(), other$info = other.getInfo();
        if (!Objects.equals(this$info, other$info)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Withdrawal;
    }


    public String toString() {
        return "Withdrawal(id=" + getId() + ", oid=" + getOid() + ", merchant=" + getMerchant() + ", uid=" + getUid() + ", points=" + getPoints() + ", chargeMoney=" + getChargeMoney() + ", realMoney=" + getRealMoney() + ", balance=" + getBalance() + ", alipayName=" + getAlipayName() + ", alipayAccount=" + getAlipayAccount() + ", paymentCode=" + getPaymentCode() + ", channel=" + getChannel() + ", info=" + getInfo() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 19 */
        return this.id;
        /*    */
    }

    public String getOid() {
        /* 21 */
        return this.oid;
        /*    */
    }

    public String getMerchant() {
        /* 23 */
        return this.merchant;
        /*    */
    }

    public Integer getUid() {
        /* 25 */
        return this.uid;
        /*    */
    }

    public Double getPoints() {
        /* 27 */
        return this.points;
        /*    */
    }

    public Double getChargeMoney() {
        /* 29 */
        return this.chargeMoney;
        /*    */
    }

    public Double getRealMoney() {
        /* 31 */
        return this.realMoney;
        /*    */
    }

    public Double getBalance() {
        /* 33 */
        return this.balance;
        /*    */
    }

    public String getAlipayName() {
        /* 35 */
        return this.alipayName;
        /*    */
    }

    public String getAlipayAccount() {
        /* 37 */
        return this.alipayAccount;
        /*    */
    }

    public String getPaymentCode() {
        /* 39 */
        return this.paymentCode;
        /*    */
    }

    public WithdrawalEnum getChannel() {
        /* 41 */
        return this.channel;
        /*    */
    }

    public String getInfo() {
        /* 43 */
        return this.info;
        /*    */
    }

    public String getState() {
        /* 45 */
        return this.state;
        /*    */
    }

    public String getCreateTime() {
        /* 47 */
        return this.createTime;
        /*    */
    }
    /*    */
}


