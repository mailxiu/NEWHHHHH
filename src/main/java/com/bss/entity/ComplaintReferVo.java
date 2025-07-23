/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
@TableName("complaint_refer")
/*    */ public class ComplaintReferVo {
    /*    */   private String name;
    /*    */   private Integer sort;
    /*    */   private Integer state;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ComplaintReferVo)) return false;
        com.bss.entity.ComplaintReferVo other = (com.bss.entity.ComplaintReferVo) o;
        if (!other.canEqual(this)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$state = getState(), other$state = other.getState();
        return !(!Objects.equals(this$state, other$state));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ComplaintReferVo;
    }



    public String toString() {
        return "ComplaintReferVo(name=" + getName() + ", sort=" + getSort() + ", state=" + getState() + ")";
    }

    /*    */
    /*    */
    public String getName() {
        /* 15 */
        return this.name;
        /*    */
    }

    /*    */
    /*    */
    public void setName(String name) {
        /* 12 */
        this.name = name;
    }

    public Integer getSort() {
        /* 17 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public Integer getState() {
        /* 19 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ComplaintReferVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */