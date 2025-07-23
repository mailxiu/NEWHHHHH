/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
/*    */ import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("extract_config")
/*    */ public class ExtractConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private Integer payMode;
    /*    */   private Double payPoints;
    /*    */   private Double payPercent;
    private Integer payStart;
    private Double automaticPayment;
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ExtractConfig)) return false;
        com.bss.entity.ExtractConfig other = (com.bss.entity.ExtractConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
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
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ExtractConfig;
    }


    public String toString() {
        return "ExtractConfig(id=" + getId() + ", payMode=" + getPayMode() + ", payPoints=" + getPayPoints() + ", payPercent=" + getPayPercent() + ", payStart=" + getPayStart() + ", automaticPayment=" + getAutomaticPayment() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /*    */
    public void setId(Integer id) {
        /* 15 */
        this.id = id;
    }

    public Integer getPayMode() {
        /* 19 */
        return this.payMode;
        /*    */
    }

    public void setPayMode(Integer payMode) {
        this.payMode = payMode;
    }

    public Double getPayPoints() {
        /* 21 */
        return this.payPoints;
        /*    */
    }

    public void setPayPoints(Double payPoints) {
        this.payPoints = payPoints;
    }

    public Double getPayPercent() {
        /* 23 */
        return this.payPercent;
        /*    */
    }

    public void setPayPercent(Double payPercent) {
        this.payPercent = payPercent;
    }

    public Integer getPayStart() {
        /* 25 */
        return this.payStart;
        /*    */
    }

    public void setPayStart(Integer payStart) {
        this.payStart = payStart;
    }

    public Double getAutomaticPayment() {
        /* 27 */
        return this.automaticPayment;
        /*    */
    }

    public void setAutomaticPayment(Double automaticPayment) {
        this.automaticPayment = automaticPayment;
    }

    public Date getCreateTime() {
        /* 29 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ExtractConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */