/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("notice")
/*    */ public class Notice implements Serializable {
    /*    */   private Object id;
    /*    */   private String merchant;
    /*    */   private String info;
    /*    */   private Integer speed;
    /*    */   private String createTime;
    /*    */   private static final long serialVersionUID = 1L;

    /*    */
    /* 14 */
    public void setId(Object id) {
        this.id = id;
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public void setSpeed(Integer speed) {
        this.speed = speed;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Notice)) return false;
        com.bss.entity.Notice other = (com.bss.entity.Notice) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$info = getInfo(), other$info = other.getInfo();
        if (!Objects.equals(this$info, other$info)) return false;
        Object this$speed = getSpeed(), other$speed = other.getSpeed();
        if (!Objects.equals(this$speed, other$speed)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Notice;
    }


    public String toString() {
        return "Notice(id=" + getId() + ", merchant=" + getMerchant() + ", info=" + getInfo() + ", speed=" + getSpeed() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    public Object getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    public String getMerchant() {
        /* 18 */
        return this.merchant;
        /*    */
    }

    public String getInfo() {
        /* 20 */
        return this.info;
        /*    */
    }

    public Integer getSpeed() {
        /* 22 */
        return this.speed;
        /*    */
    }

    public String getCreateTime() {
        /* 24 */
        return this.createTime;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Notice.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */