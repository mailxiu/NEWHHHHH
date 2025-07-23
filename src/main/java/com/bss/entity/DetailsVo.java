/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
@TableName("markdown")
/*    */ public class DetailsVo {
    /*    */   private Integer pid;
    /*    */   private String md;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.DetailsVo)) return false;
        com.bss.entity.DetailsVo other = (com.bss.entity.DetailsVo) o;
        if (!other.canEqual(this)) return false;
        Object this$pid = getPid(), other$pid = other.getPid();
        if (!Objects.equals(this$pid, other$pid)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        return !(!Objects.equals(this$md, other$md));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.DetailsVo;
    }



    public String toString() {
        return "DetailsVo(pid=" + getPid() + ", md=" + getMd() + ")";
    }

    /*    */
    /*    */
    public Integer getPid() {
        /* 13 */
        return this.pid;
        /*    */
    }

    /*    */
    /* 10 */
    public void setPid(Integer pid) {
        this.pid = pid;
    }

    public String getMd() {
        /* 15 */
        return this.md;
        /*    */
    }

    public void setMd(String md) {
        this.md = md;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\DetailsVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */