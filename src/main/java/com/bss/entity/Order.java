/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;
import com.bss.enmus.PaymentEnum;
/*    */ import java.io.Serializable;
import java.math.BigDecimal;
/*    */ import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("orders")
/*    */ public class Order implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String uid;
    /*    */   private String oid;
    /*    */   private String partner;
    /*    */   private Integer sort;
    private BigDecimal money;
    private String transactionId;
    private PaymentEnum paymentType;
    private String state;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Order)) return false;
        com.bss.entity.Order other = (com.bss.entity.Order) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$oid = getOid(), other$oid = other.getOid();
        if (!Objects.equals(this$oid, other$oid)) return false;
        Object this$partner = getPartner(), other$partner = other.getPartner();
        if (!Objects.equals(this$partner, other$partner)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$money = getMoney(), other$money = other.getMoney();
        if (!Objects.equals(this$money, other$money)) return false;
        Object this$transactionId = getTransactionId(), other$transactionId = other.getTransactionId();
        if (!Objects.equals(this$transactionId, other$transactionId))
            return false;
        Object this$paymentType = getPaymentType(), other$paymentType = other.getPaymentType();
        if (!Objects.equals(this$paymentType, other$paymentType))
            return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Order;
    }


    public String toString() {
        return "Order(id=" + getId() + ", uid=" + getUid() + ", oid=" + getOid() + ", partner=" + getPartner() + ", sort=" + getSort() + ", money=" + getMoney() + ", transactionId=" + getTransactionId() + ", paymentType=" + getPaymentType() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 19 */
        return this.id;
        /*    */
    }

    /*    */
    /* 16 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getUid() {
        /* 21 */
        return this.uid;
        /*    */
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getOid() {
        /* 23 */
        return this.oid;
        /*    */
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getPartner() {
        /* 25 */
        return this.partner;
        /*    */
    }

    public void setPartner(String partner) {
        this.partner = partner;
    }

    public Integer getSort() {
        /* 27 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public BigDecimal getMoney() {
        /* 29 */
        return this.money;
        /*    */
    }

    public void setMoney(BigDecimal money) {
        this.money = money;
    }

    public String getTransactionId() {
        /* 31 */
        return this.transactionId;
        /*    */
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public PaymentEnum getPaymentType() {
        /* 33 */
        return this.paymentType;
        /*    */
    }

    public void setPaymentType(PaymentEnum paymentType) {
        this.paymentType = paymentType;
    }

    public String getState() {
        /* 35 */
        return this.state;
        /*    */
    }

    public void setState(String state) {
        this.state = state;
    }

    /*    */
    public Date getCreateTime() {
        /* 38 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Order.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */