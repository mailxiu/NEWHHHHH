/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
/*    */ import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("advertise")
/*    */ public class Advertise implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private String md;
    private Integer orient;
    private Integer state;
    private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Advertise)) return false;
        com.bss.entity.Advertise other = (com.bss.entity.Advertise) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        if (!Objects.equals(this$md, other$md)) return false;
        Object this$orient = getOrient(), other$orient = other.getOrient();
        if (!Objects.equals(this$orient, other$orient)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Advertise;
    }


    public String toString() {
        return "Advertise(id=" + getId() + ", merchant=" + getMerchant() + ", md=" + getMd() + ", orient=" + getOrient() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getMerchant() {
        /* 19 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public String getMd() {
        /* 21 */
        return this.md;
        /*    */
    }

    public void setMd(String md) {
        this.md = md;
    }

    public Integer getOrient() {
        /* 23 */
        return this.orient;
        /*    */
    }

    public void setOrient(Integer orient) {
        this.orient = orient;
    }

    public Integer getState() {
        /* 25 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public String getCreateTime() {
        /* 27 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Advertise.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */