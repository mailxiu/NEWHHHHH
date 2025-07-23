/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;
/*    */
/*    */ import java.math.BigDecimal;
/*    */ import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("deposit")
/*    */ public class Deposit {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String uid;
    /*    */   private BigDecimal money;
    private Boolean state;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date updateTime;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Deposit)) return false;
        com.bss.entity.Deposit other = (com.bss.entity.Deposit) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$money = getMoney(), other$money = other.getMoney();
        if (!Objects.equals(this$money, other$money)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$updateTime = getUpdateTime(), other$updateTime = other.getUpdateTime();
        if (!Objects.equals(this$updateTime, other$updateTime))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Deposit;
    }


    public String toString() {
        return "Deposit(id=" + getId() + ", uid=" + getUid() + ", money=" + getMoney() + ", state=" + getState() + ", updateTime=" + getUpdateTime() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 18 */
        return this.id;
        /*    */
    }

    /*    */
    /* 15 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getUid() {
        /* 20 */
        return this.uid;
        /*    */
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public BigDecimal getMoney() {
        /* 22 */
        return this.money;
        /*    */
    }

    public void setMoney(BigDecimal money) {
        this.money = money;
    }

    public Boolean getState() {
        /* 24 */
        return this.state;
        /*    */
    }

    public void setState(Boolean state) {
        this.state = state;
    }

    /*    */
    public Date getUpdateTime() {
        /* 27 */
        return this.updateTime;
        /*    */
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    /*    */
    public Date getCreateTime() {
        /* 30 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Deposit.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */