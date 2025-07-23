/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;
/*    */
/*    */ import java.io.Serializable;
/*    */ import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("details")
/*    */ public class Details implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private Integer pid;
    private String md;
    private Integer look;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Details)) return false;
        com.bss.entity.Details other = (com.bss.entity.Details) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$pid = getPid(), other$pid = other.getPid();
        if (!Objects.equals(this$pid, other$pid)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        if (!Objects.equals(this$md, other$md)) return false;
        Object this$look = getLook(), other$look = other.getLook();
        if (!Objects.equals(this$look, other$look)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Details;
    }


    public String toString() {
        return "Details(id=" + getId() + ", merchant=" + getMerchant() + ", pid=" + getPid() + ", md=" + getMd() + ", look=" + getLook() + ", createTime=" + getCreateTime() + ")";
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

    public String getMerchant() {
        /* 20 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public Integer getPid() {
        /* 22 */
        return this.pid;
        /*    */
    }

    public void setPid(Integer pid) {
        this.pid = pid;
    }

    public String getMd() {
        /* 24 */
        return this.md;
        /*    */
    }

    public void setMd(String md) {
        this.md = md;
    }

    public Integer getLook() {
        /* 26 */
        return this.look;
        /*    */
    }

    public void setLook(Integer look) {
        this.look = look;
    }

    /*    */
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


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Details.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */